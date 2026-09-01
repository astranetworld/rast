// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Turning an Engine API payload back into the block that was hashed.
//!
//! An execution payload carries no `ommers_hash` and no `difficulty`; reth
//! fills in the post-merge values (the empty-list hash, zero) and checks that
//! the result hashes to the payload's block hash. A gov5 HotStuff header has
//! a zero ommers hash, so under that rule every block a Go member produces —
//! and every block this node's own validator process seals — is "block hash
//! mismatch". This validator knows the chain's header profile and, on a
//! HotStuff chain, reconstructs gov5's shape instead, letting the hash pick
//! between the variants gov5 has produced over time. Nothing is guessed: a
//! payload whose header hashes to none of them is refused exactly as before.
//!
//! Everything else reth checks about a payload — versioned hashes, fork
//! fields, the blob schedule — still runs, on the payload with its hash
//! adjusted to the Ethereum-shaped header so reth's own hash check passes.

use alloy_primitives::B256;
use alloy_rpc_types_engine::{ExecutionData, PayloadAttributes as EthPayloadAttributes, PayloadError};
use n42_h2_consensus::header_profile::N42HeaderProfile;
use n42_h2_consensus::reconstruct_gov5_h2_block_from;
use n42_qmdb_reth::HotStuffGenesisConfig;
use reth_chainspec::{EthChainSpec, EthereumHardforks};
use reth_engine_primitives::{EngineApiValidator, EngineTypes, PayloadValidator};
use reth_ethereum_primitives::{Block as EthBlock, EthPrimitives, TransactionSigned};
use reth_node_api::{AddOnsContext, FullNodeComponents, NodeTypes};
use reth_node_builder::rpc::PayloadValidatorBuilder;
use reth_node_ethereum::node::EthereumEngineValidator;
use reth_payload_primitives::{
    EngineApiMessageVersion, EngineObjectValidationError, NewPayloadError, PayloadOrAttributes,
    PayloadTypes,
};
use reth_primitives_traits::SealedBlock;
use std::sync::Arc;

/// The header profile a chain uses, read from its genesis.
///
/// A genesis that names a `hotstuff` validator set is driven by HotStuff-2
/// and its blocks are gov5-shaped; anything else is Ethereum-shaped.
pub fn header_profile_for<ChainSpec: EthChainSpec>(chain_spec: &ChainSpec) -> N42HeaderProfile {
    if HotStuffGenesisConfig::from_genesis(chain_spec.genesis()).is_ok() {
        N42HeaderProfile::Gov5H2
    } else {
        N42HeaderProfile::Ethereum
    }
}

/// reth's Ethereum payload validator, plus the chain's header profile.
#[derive(Clone, Debug)]
pub struct N42EngineValidator<ChainSpec> {
    inner: EthereumEngineValidator<ChainSpec>,
    /// The same chain spec `inner` holds, for the fork checks this validator
    /// runs itself.
    chain_spec: Arc<ChainSpec>,
    profile: N42HeaderProfile,
}

impl<ChainSpec> N42EngineValidator<ChainSpec> {
    /// A validator for `chain_spec` under `profile`.
    pub fn new(chain_spec: Arc<ChainSpec>, profile: N42HeaderProfile) -> Self {
        Self {
            inner: EthereumEngineValidator::new(chain_spec.clone()),
            chain_spec,
            profile,
        }
    }

    /// The profile in force.
    pub const fn profile(&self) -> N42HeaderProfile {
        self.profile
    }
}

impl<ChainSpec, Types> PayloadValidator<Types> for N42EngineValidator<ChainSpec>
where
    ChainSpec: EthChainSpec + EthereumHardforks + 'static,
    Types: PayloadTypes<ExecutionData = ExecutionData>,
{
    type Block = EthBlock;

    fn convert_payload_to_block(
        &self,
        payload: ExecutionData,
    ) -> Result<SealedBlock<Self::Block>, NewPayloadError> {
        if self.profile == N42HeaderProfile::Ethereum {
            return <EthereumEngineValidator<ChainSpec> as PayloadValidator<Types>>::convert_payload_to_block(
                &self.inner,
                payload,
            );
        }

        let expected_hash = payload.block_hash();

        // Decoded once. This used to be three full conversions of the same
        // payload -- the reconstruction, a second to learn the Ethereum-shaped
        // hash, and a third inside reth's well-formedness check -- each of
        // them 163,000 transaction decodes, a hash per transaction and the
        // transactions trie, on the follower's critical path before the block
        // was even handed to the engine. A CPU profile of a follower showed
        // the conversion thread as busy as the execution thread.
        let ethereum_shaped = payload
            .payload
            .clone()
            .try_into_block_with_sidecar::<TransactionSigned>(&payload.sidecar)?;
        let ethereum_shaped = SealedBlock::seal_slow(ethereum_shaped);

        // reth's checks on the Ethereum-shaped block, the same ones its own
        // validator runs after converting: fork fields and sidecar shape. Its
        // verdict on those is the one that counts; the hash comparison is
        // this validator's, against gov5's header, below.
        let timestamp = ethereum_shaped.timestamp;
        reth_payload_validator::shanghai::ensure_well_formed_fields(
            ethereum_shaped.body(),
            self.chain_spec.is_shanghai_active_at_timestamp(timestamp),
        )?;
        reth_payload_validator::cancun::ensure_well_formed_fields(
            &ethereum_shaped,
            payload.sidecar.cancun(),
            self.chain_spec.is_cancun_active_at_timestamp(timestamp),
        )?;
        reth_payload_validator::prague::ensure_well_formed_fields(
            ethereum_shaped.body(),
            payload.sidecar.prague(),
            self.chain_spec.is_prague_active_at_timestamp(timestamp),
        )?;

        // The block gov5 hashed: header profile checked, ommers hash and
        // difficulty restored, hash confirmed -- header arithmetic on the
        // block already decoded.
        let block = reconstruct_gov5_h2_block_from(ethereum_shaped.into_block(), &payload)
            .map_err(|err| NewPayloadError::Other(err.into()))?;

        let sealed = SealedBlock::seal_slow(block);
        if sealed.hash() != expected_hash {
            // Cannot happen after reconstruction confirmed the hash; kept
            // so a future change to either side fails loudly.
            return Err(PayloadError::BlockHash {
                execution: sealed.hash(),
                consensus: expected_hash,
            }
            .into());
        }
        Ok(sealed)
    }
}

impl<ChainSpec, Types> EngineApiValidator<Types> for N42EngineValidator<ChainSpec>
where
    ChainSpec: EthChainSpec + EthereumHardforks + 'static,
    Types: PayloadTypes<PayloadAttributes = EthPayloadAttributes, ExecutionData = ExecutionData>,
{
    fn validate_version_specific_fields(
        &self,
        version: EngineApiMessageVersion,
        payload_or_attrs: PayloadOrAttributes<'_, ExecutionData, EthPayloadAttributes>,
    ) -> Result<(), EngineObjectValidationError> {
        <EthereumEngineValidator<ChainSpec> as EngineApiValidator<Types>>::validate_version_specific_fields(
            &self.inner,
            version,
            payload_or_attrs,
        )
    }

    fn ensure_well_formed_attributes(
        &self,
        version: EngineApiMessageVersion,
        attributes: &EthPayloadAttributes,
    ) -> Result<(), EngineObjectValidationError> {
        <EthereumEngineValidator<ChainSpec> as EngineApiValidator<Types>>::ensure_well_formed_attributes(
            &self.inner,
            version,
            attributes,
        )
    }
}

/// Builds [`N42EngineValidator`] for the node, reading the profile from the
/// chain it is launched on.
#[derive(Clone, Copy, Debug, Default)]
pub struct N42EngineValidatorBuilder;

impl<Node, Types> PayloadValidatorBuilder<Node> for N42EngineValidatorBuilder
where
    Types: NodeTypes<
        ChainSpec: EthChainSpec + EthereumHardforks + Clone + 'static,
        Payload: EngineTypes<ExecutionData = ExecutionData>
                     + PayloadTypes<PayloadAttributes = EthPayloadAttributes>,
        Primitives = EthPrimitives,
    >,
    Node: FullNodeComponents<Types = Types>,
{
    type Validator = N42EngineValidator<Types::ChainSpec>;

    async fn build(self, ctx: &AddOnsContext<'_, Node>) -> eyre::Result<Self::Validator> {
        let chain_spec = ctx.config.chain.clone();
        let profile = header_profile_for(chain_spec.as_ref());
        Ok(N42EngineValidator::new(chain_spec, profile))
    }
}

/// Convenience for tests and callers holding a hash: is this the value
/// gov5's producer leaves in `ommers_hash`?
pub fn is_gov5_ommers_hash(hash: B256) -> bool {
    hash == B256::ZERO
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::{Header, EMPTY_OMMER_ROOT_HASH, EMPTY_ROOT_HASH};
    use alloy_eips::eip7685::EMPTY_REQUESTS_HASH;
    use alloy_primitives::{Bytes, U256};
    use n42_h2_consensus::{block_for_header, execution_data_for_block, HeaderExtra, GOV5_NIL_HASH};
    use reth_chainspec::{ChainSpec, MAINNET};
    use reth_node_ethereum::EthEngineTypes;

    fn gov5_header(ommers_hash: B256, difficulty: U256) -> Header {
        Header {
            parent_hash: B256::repeat_byte(1),
            ommers_hash,
            state_root: B256::repeat_byte(2),
            transactions_root: EMPTY_ROOT_HASH,
            receipts_root: GOV5_NIL_HASH,
            difficulty,
            number: 7,
            gas_limit: 30_000_000,
            // Post-Prague on mainnet, so reth's fork checks want every field.
            timestamp: 1_800_000_000,
            extra_data: HeaderExtra::for_view(7).encode(),
            base_fee_per_gas: Some(7),
            withdrawals_root: Some(EMPTY_ROOT_HASH),
            blob_gas_used: Some(0),
            excess_blob_gas: Some(0),
            parent_beacon_block_root: Some(B256::ZERO),
            requests_hash: Some(EMPTY_REQUESTS_HASH),
            ..Default::default()
        }
    }

    fn payload_for(header: Header) -> ExecutionData {
        let block = block_for_header(header, vec![]);
        execution_data_for_block(block.header.hash_slow(), &block)
    }

    fn validator(profile: N42HeaderProfile) -> N42EngineValidator<ChainSpec> {
        N42EngineValidator::new(MAINNET.clone(), profile)
    }

    fn convert(
        validator: &N42EngineValidator<ChainSpec>,
        payload: ExecutionData,
    ) -> Result<SealedBlock<EthBlock>, NewPayloadError> {
        <N42EngineValidator<ChainSpec> as PayloadValidator<EthEngineTypes>>::convert_payload_to_block(
            validator, payload,
        )
    }

    #[test]
    fn a_gov5_block_reconstructs_with_its_zero_ommers_hash() {
        let payload = payload_for(gov5_header(B256::ZERO, U256::ZERO));
        let expected = payload.block_hash();
        let sealed = convert(&validator(N42HeaderProfile::Gov5H2), payload).unwrap();
        assert_eq!(sealed.hash(), expected);
        assert_eq!(sealed.header().ommers_hash, B256::ZERO);
        assert!(is_gov5_ommers_hash(sealed.header().ommers_hash));
    }

    #[test]
    fn the_legacy_difficulty_one_range_still_reconstructs() {
        let payload = payload_for(gov5_header(B256::ZERO, U256::from(1)));
        let expected = payload.block_hash();
        let sealed = convert(&validator(N42HeaderProfile::Gov5H2), payload).unwrap();
        assert_eq!(sealed.hash(), expected);
        assert_eq!(sealed.header().difficulty, U256::from(1));
    }

    #[test]
    fn the_ethereum_profile_refuses_what_it_always_refused() {
        // Under reth's rules a zero-ommers header cannot be reconstructed
        // and the payload is a hash mismatch. Installing the gov5 profile on
        // an Ethereum chain would change that, which is why it is read from
        // the genesis and not configured.
        let payload = payload_for(gov5_header(B256::ZERO, U256::ZERO));
        assert!(convert(&validator(N42HeaderProfile::Ethereum), payload).is_err());

        let ethereum = payload_for(gov5_header(EMPTY_OMMER_ROOT_HASH, U256::ZERO));
        let expected = ethereum.block_hash();
        assert_eq!(convert(&validator(N42HeaderProfile::Ethereum), ethereum).unwrap().hash(), expected);
    }

    #[test]
    fn a_tampered_hash_is_refused_under_both_profiles() {
        let mut payload = payload_for(gov5_header(B256::ZERO, U256::ZERO));
        payload.payload.as_v1_mut().block_hash = B256::repeat_byte(0xEE);
        assert!(convert(&validator(N42HeaderProfile::Gov5H2), payload.clone()).is_err());
        assert!(convert(&validator(N42HeaderProfile::Ethereum), payload).is_err());
    }

    #[test]
    fn a_header_without_the_magic_is_not_a_gov5_block() {
        let mut header = gov5_header(B256::ZERO, U256::ZERO);
        header.extra_data = Bytes::from_static(b"not-n42h-but-long-enough-for-the-check");
        let payload = payload_for(header);
        assert!(convert(&validator(N42HeaderProfile::Gov5H2), payload).is_err());
    }
}
