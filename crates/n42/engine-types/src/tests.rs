// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Tests for N42 engine types

use super::*;

mod node_tests {
    use super::*;
    use reth_chainspec::ChainSpec;
    use reth_node_api::NodeTypes;

    #[test]
    fn test_n42_node_types() {
        // Verify N42Node implements NodeTypes
        fn assert_node_types<T: NodeTypes>() {}
        assert_node_types::<N42Node>();
    }

    #[test]
    fn test_n42_node_chain_spec() {
        // Verify N42Node uses ChainSpec
        fn check_chain_spec<T: NodeTypes<ChainSpec = ChainSpec>>() {}
        check_chain_spec::<N42Node>();
    }

    #[test]
    fn test_n42_node_primitives() {
        use n42_tx_types::N42Primitives as EthPrimitives;
        // Verify N42Node uses EthPrimitives
        fn check_primitives<T: NodeTypes<Primitives = EthPrimitives>>() {}
        check_primitives::<N42Node>();
    }
}

mod consensus_builder_tests {
    use super::*;

    #[test]
    fn test_consensus_builder_default() {
        let builder = N42ConsensusBuilder::default();
        // Just verify it can be created
        let _ = format!("{:?}", builder);
    }

    #[test]
    fn test_consensus_builder_clone() {
        let builder1 = N42ConsensusBuilder::default();
        let builder2 = builder1.clone();
        // Both should be equal (Copy)
        let _ = builder2;
    }
}

mod payload_builder_tests {
    use crate::payload::EthereumPayloadBuilderWrapper;

    #[test]
    fn test_ethereum_payload_builder_wrapper_default() {
        let wrapper = EthereumPayloadBuilderWrapper::default();
        // Verify default construction
        let _ = format!("{:?}", wrapper);
    }

    #[test]
    fn test_ethereum_payload_builder_wrapper_clone() {
        let wrapper1 = EthereumPayloadBuilderWrapper::default();
        let wrapper2 = wrapper1.clone();
        // Both should work
        let _ = format!("{:?}", wrapper2);
    }
}
