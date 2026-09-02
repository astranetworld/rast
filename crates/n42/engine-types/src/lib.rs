// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//mod addons;
//pub use addons::N42NodeAddOns;

//mod engine_type;
//pub use engine_type::N42EngineTypes;

// mod attributes;
// pub use attributes::N42PayloadAttributes;
// pub use attributes::N42PayloadBuilderAttributes;

//mod engine_validator;
//pub use engine_validator::N42EngineValidator;

mod node;
pub use node::N42Node;

mod payload;
pub mod assembler;
pub mod built_executions;
//mod job_generator;
//mod job;
//mod metrics;
mod consensus;
pub mod engine_validator;
pub mod hotstuff_consensus;
mod network;

pub use consensus::{is_hotstuff_chain, N42Consensus, N42ConsensusBuilder, N42FullConsensus};
pub use engine_validator::{header_profile_for, N42EngineValidator, N42EngineValidatorBuilder};
pub use hotstuff_consensus::{gov5_receipt_root_bloom, HotStuffConsensus};
pub use payload::N42PayloadServiceBuilder;

#[cfg(test)]
mod tests;

//
// #[tokio::main]
// async fn main() -> eyre::Result<()> {
//     let _guard = RethTracer::new().init()?;
//
//     let tasks = TaskManager::current();
//
//     // create optimism genesis with canyon at block 2
//     let spec = ChainSpec::builder()
//         .chain(Chain::mainnet())
//         .genesis(Genesis::default())
//         .london_activated()
//         .paris_activated()
//         .shanghai_activated()
//         .build();
//
//     // create node config
//     let node_config =
//         NodeConfig::test().with_rpc(RpcServerArgs::default().with_http()).with_chain(spec);
//
//     let handle = NodeBuilder::new(node_config)
//         .testing_node(tasks.executor())
//         .launch_node(MyCustomNode::default())
//         .await
//         .unwrap();
//
//     println!("Node started");
//
//     handle.node_exit_future.await
// }
